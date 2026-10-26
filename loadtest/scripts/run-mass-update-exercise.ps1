# AA10-T12 - a mass update under interactive load.
#
# Runs k6/crud_read.js (the interactive read class) for -DurationSeconds,
# starts a background mass update of -Rows loadtest_bulk records through
# POST /api/v1/loadtest_bulk/mass at -MassStartSecond, keeps reading until
# the end, then reports the interactive read p95 in three phases:
#   - before : from the start to the mass update's start;
#   - during : while the mass operation is queued or running;
#   - after  : from the operation's end to the end of the run;
# and the operation's own records per second (rows_done over its run time).
#
# The chunks pace themselves on the node's load (attome_jobs::throttle,
# AA10-T6), so "during" is the number that shows whether that pacing keeps
# interactive reads inside their budget.
#
# Requires seed.ps1 to have run with a profile whose loadtest_bulk holds at
# least -Rows records (solo seeds 1,000,000). Never point it at the shared
# dev server: it starts its own loadtest nodes (Start-LoadtestNodes) on the
# loadtest stack.
#
# Usage:
#   ./scripts/run-mass-update-exercise.ps1 -Plan      # print the phases, run nothing
#   $env:LOADTEST_ACK = "yes"
#   docker compose -f docker-compose.loadtest.yml up -d
#   ./scripts/seed.ps1
#   ./scripts/run-mass-update-exercise.ps1
param(
    [int]$NodeCount = 1,
    [int]$DurationSeconds = 60,
    [int]$MassStartSecond = 10,
    [int]$Rows = 100000,
    [int]$ReadVUs = 20,
    [switch]$Plan
)

if ($Plan) {
    Write-Host "Mass update under load (AA10-T12):"
    Write-Host "  1. before : k6 crud_read.js with $ReadVUs VUs from second 0 to second $MassStartSecond."
    Write-Host "  2. during : at second $MassStartSecond, POST /api/v1/loadtest_bulk/mass/estimate, then"
    Write-Host "              POST /api/v1/loadtest_bulk/mass (update of seq <= $Rows, confirm_estimate_rows);"
    Write-Host "              poll GET /api/v1/mass/{id} until it is done; reads continue."
    Write-Host "  3. after  : reads continue to second $DurationSeconds."
    Write-Host "  Report: the read p95 per phase, and the operation's records per second."
    exit 0
}

. "$PSScriptRoot/common.ps1"
Assert-LoadtestSafety

$seedInfoPath = Join-Path $script:GenDir "seed-info.json"
if (-not (Test-Path $seedInfoPath)) {
    throw "loadtest/.generated/seed-info.json not found - run seed.ps1 first."
}
$seed = Get-Content $seedInfoPath -Raw | ConvertFrom-Json

function Invoke-MassApi {
    # curl, not Invoke-RestMethod, for the reason seed.ps1 gives; the
    # Sec-Fetch-Site header is the browser signal csrf_protect needs on a
    # cookie-authenticated POST.
    param($Method, $BaseUrl, $Path, $CookieJar, $Body = $null)
    $curlArgs = @("-s", "-X", $Method.ToUpper(), "$BaseUrl$Path",
        "-H", "Content-Type: application/json",
        "-H", "Sec-Fetch-Site: same-origin",
        "-b", $CookieJar, "-c", $CookieJar,
        "-w", "`n%{http_code}")
    $bodyFile = $null
    if ($null -ne $Body) {
        $bodyFile = Join-Path $script:GenDir "mass-body-$([guid]::NewGuid()).json"
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

function Get-P95 {
    param([double[]]$Values)
    if (-not $Values -or $Values.Count -eq 0) { return $null }
    $sorted = $Values | Sort-Object
    $index = [Math]::Max(0, [Math]::Ceiling(0.95 * $sorted.Count) - 1)
    return [Math]::Round($sorted[$index], 1)
}

Write-Host "=== Starting $NodeCount node(s) ==="
$ports = Start-LoadtestNodes -Count $NodeCount -BootstrapAdminEmail $seed.admin_email
Start-Sleep -Seconds 2
$baseUrl = "http://127.0.0.1:$($ports[0])"
$baseUrlsDocker = ($ports | ForEach-Object { "http://host.docker.internal:$_" }) -join ','

$adminJar = Join-Path $script:GenDir "mass-admin-cookies.txt"
Remove-Item $adminJar -ErrorAction SilentlyContinue
Invoke-MassApi -Method Post -BaseUrl $baseUrl -Path "/api/v1/auth/login" -CookieJar $adminJar `
    -Body @{ email = $seed.admin_email; password = $seed.admin_password } | Out-Null

$pointsPath = Join-Path $script:ResultsDir "mass-update-read-points.json"
if (Test-Path $pointsPath) { Remove-Item $pointsPath -Force }

Write-Host "=== Phase 1 (before): crud_read.js, $ReadVUs VUs for ${DurationSeconds}s ==="
$runStart = [DateTimeOffset]::UtcNow
$k6Job = Start-Job -ScriptBlock {
    param($dir, $urls, $email, $password, $entity, $queryId, $vus, $seconds)
    & docker run --rm -v "${dir}:/work" `
        -e "BASE_URLS=$urls" -e "TEST_EMAIL=$email" -e "TEST_PASSWORD=$password" `
        -e "BULK_ENTITY=$entity" -e "BULK_QUERY_ID=$queryId" `
        -e "VUS=$vus" -e "DURATION=${seconds}s" `
        grafana/k6 run "/work/k6/crud_read.js" --out "json=/work/results/mass-update-read-points.json"
    $LASTEXITCODE
} -ArgumentList $script:LoadtestDir, $baseUrlsDocker, $seed.test_email, $seed.test_password, `
    $seed.bulk_entity, $seed.bulk_query_id, $ReadVUs, $DurationSeconds

Start-Sleep -Seconds $MassStartSecond

Write-Host "=== Phase 2 (during): mass update of seq <= $Rows ==="
$filter = @{ kind = "compare"; field = "seq"; op = "lte"; value = $Rows }
$payload = @{ title = "mass-exercise-$((Get-Date).ToString('yyyyMMddHHmmss'))" }
$estimate = Invoke-MassApi -Method Post -BaseUrl $baseUrl -Path "/api/v1/loadtest_bulk/mass/estimate" `
    -CookieJar $adminJar -Body @{ filter = $filter; kind = "update"; payload = $payload }
Write-Host "  estimate: $($estimate.estimated_rows) rows, $($estimate.path), ~$($estimate.estimated_seconds)s"
$massStart = [DateTimeOffset]::UtcNow
$run = Invoke-MassApi -Method Post -BaseUrl $baseUrl -Path "/api/v1/loadtest_bulk/mass" -CookieJar $adminJar `
    -Body @{ filter = $filter; kind = "update"; payload = $payload; reason = "AA10-T12 exercise";
             confirm_estimate_rows = $estimate.exact_upto }
$operationId = $run.operation.id
$operation = $run.operation
while ($operation.status -in @("queued", "running")) {
    if (([DateTimeOffset]::UtcNow - $runStart).TotalSeconds -gt ($DurationSeconds + 600)) {
        Write-Warning "the mass operation is still $($operation.status) ten minutes after the reads ended"
        break
    }
    Start-Sleep -Seconds 2
    $operation = Invoke-MassApi -Method Get -BaseUrl $baseUrl -Path "/api/v1/mass/$operationId" -CookieJar $adminJar
}
$massEnd = [DateTimeOffset]::UtcNow
Write-Host "  operation $operationId : $($operation.status), $($operation.rows_done) done, $($operation.rows_conflict) conflicts"

Write-Host "=== Phase 3 (after): reads continue to the end ==="
$k6Exit = Receive-Job -Job $k6Job -Wait -AutoRemoveJob | Select-Object -Last 1
Stop-LoadtestNodes

if (-not (Test-Path $pointsPath)) {
    Write-Warning "k6 wrote no points (exit $k6Exit) - check the docker run output."
    exit 1
}

# One JSON object per line; only the request durations matter.
$before = [System.Collections.Generic.List[double]]::new()
$during = [System.Collections.Generic.List[double]]::new()
$after = [System.Collections.Generic.List[double]]::new()
foreach ($line in [System.IO.File]::ReadLines($pointsPath)) {
    if ($line -notmatch '"metric":"http_req_duration"' -or $line -notmatch '"type":"Point"') { continue }
    $point = $line | ConvertFrom-Json
    $at = [DateTimeOffset]::Parse($point.data.time)
    $ms = [double]$point.data.value
    if ($at -lt $massStart) { $before.Add($ms) }
    elseif ($at -le $massEnd) { $during.Add($ms) }
    else { $after.Add($ms) }
}

$opSeconds = if ($operation.finished_at) {
    ([DateTimeOffset]::Parse($operation.finished_at) - [DateTimeOffset]::Parse($operation.created_at)).TotalSeconds
} else { ($massEnd - $massStart).TotalSeconds }
$rowsPerSecond = if ($opSeconds -gt 0) { [Math]::Round($operation.rows_done / $opSeconds, 1) } else { $null }

$rows = @(
    [PSCustomObject]@{ phase = "before"; requests = $before.Count; p95_ms = Get-P95 $before.ToArray() }
    [PSCustomObject]@{ phase = "during"; requests = $during.Count; p95_ms = Get-P95 $during.ToArray() }
    [PSCustomObject]@{ phase = "after"; requests = $after.Count; p95_ms = Get-P95 $after.ToArray() }
)
$rows | Format-Table -AutoSize
Write-Host "Mass update: $($operation.rows_done) records in $([Math]::Round($opSeconds, 1))s = $rowsPerSecond records/s"

$output = [PSCustomObject]@{
    node_count         = $NodeCount
    read_vus           = $ReadVUs
    duration_seconds   = $DurationSeconds
    mass_start_second  = $MassStartSecond
    rows_requested     = $Rows
    operation_id       = $operationId
    operation_status   = $operation.status
    rows_done          = $operation.rows_done
    rows_conflict      = $operation.rows_conflict
    rows_per_second    = $rowsPerSecond
    read_p95_before_ms = $rows[0].p95_ms
    read_p95_during_ms = $rows[1].p95_ms
    read_p95_after_ms  = $rows[2].p95_ms
    k6_exit_code       = $k6Exit
}
$outPath = Join-Path $script:ResultsDir "mass-update-exercise.json"
[System.IO.File]::WriteAllText($outPath, ($output | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Wrote $outPath"
