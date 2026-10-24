# AA1-T9: the customer-run bench. Runs the standard production mix
# (k6/production_mix.js) against a running deployment on the customer's own
# hardware and prints its p50/p95/p99 per operation class next to the
# published numbers for the profile.
#
#   pwsh -File loadtest/scripts/bench.ps1 -BaseUrl https://crm.example.com `
#     -ApiKey "<public>:<secret>" -Profile solo -Published docs/evidence/latency-1.0.0.json
#
# Four steps:
#   1. Seed: the entity bench_load (title, seq) and a stored query over it,
#      created once through the admin API and reused, then -Rows records
#      through the bulk API. Nothing outside bench_load is read or written.
#   2. Run: production_mix.js at the profile's two lowest concurrency levels
#      (loadtest/profiles.json), with the API key on every request.
#   3. Compare: bench-compare.mjs prints the table.
#   4. Clean up: every bench_load record is deleted through the bulk API;
#      the entity itself stays for the next run.
#
# The API key must belong to an administrator (system.admin): creating the
# entity and its stored query is an admin operation. When the deployment
# records metadata changes in required mode, pass -Changeset with an open
# changeset's id; it is sent as X-Attome-Changeset.
#
# Needs k6 on the PATH, or Docker (grafana/k6), and Node.js for the
# comparison. -Plan prints the steps and exits without any call.
param(
    [string]$BaseUrl = "http://127.0.0.1:7865",
    [string]$ApiKey = $env:ATTOME_API_KEY,
    [string]$Profile = "solo",
    [string]$Published = "",
    [int]$Rows = 10000,
    [string]$Duration = "60s",
    [string]$Changeset = "",
    [switch]$KeepRecords,
    [switch]$Plan
)

$ErrorActionPreference = "Stop"
$LoadtestDir = Split-Path -Parent $PSScriptRoot
$ResultsDir = Join-Path $LoadtestDir "results"
$Entity = "bench_load"
$QueryName = "bench_load_list"
$BaseUrl = $BaseUrl.TrimEnd('/')

$profiles = Get-Content (Join-Path $LoadtestDir "profiles.json") -Raw | ConvertFrom-Json
$profileInfo = $profiles.$Profile
if ($null -eq $profileInfo -or $Profile -eq "_comment") {
    throw "Unknown profile '$Profile'; profiles.json has: $(($profiles.PSObject.Properties.Name | Where-Object { $_ -ne '_comment' }) -join ', ')"
}
$levels = @($profileInfo.concurrency_levels | Sort-Object | Select-Object -First 2)

if ($Plan) {
    Write-Host "Bench plan for $BaseUrl, profile ${Profile}:"
    Write-Host "  1. seed: entity $Entity (title, seq) and stored query $QueryName through the admin API, then $Rows records through the bulk API"
    Write-Host "  2. run: k6/production_mix.js for $Duration at concurrency $($levels -join ' and '), rate $($profileInfo.rated_rps) requests a second"
    Write-Host "  3. compare: bench-compare.mjs, your p50/p95/p99 next to $(if ($Published) { $Published } else { 'no published report (pass -Published)' })"
    Write-Host "  4. clean up: delete every $Entity record through the bulk API$(if ($KeepRecords) { ' (skipped: -KeepRecords)' })"
    exit 0
}

if (-not $ApiKey) { throw "Pass -ApiKey '<public>:<secret>' (or set ATTOME_API_KEY): an administrator's API key." }
if ($Published -and -not (Test-Path $Published)) { throw "The published report '$Published' does not exist." }
New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null

$headers = @{ Authorization = "ApiKey $ApiKey" }
if ($Changeset) { $headers["X-Attome-Changeset"] = $Changeset }

# One API call; returns the parsed body, or $null for a 409 when -AllowConflict.
function Invoke-Bench {
    param([string]$Method, [string]$Path, $Body = $null, [switch]$AllowConflict)
    $req = @{ Method = $Method; Uri = "$BaseUrl$Path"; Headers = $headers; ContentType = "application/json" }
    if ($null -ne $Body) { $req.Body = ($Body | ConvertTo-Json -Depth 10 -Compress) }
    try {
        return Invoke-RestMethod @req
    } catch {
        $status = $null
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        if ($AllowConflict -and $status -eq 409) { return $null }
        if ($status -eq 401) { throw "$Method $Path -> 401: the API key was refused." }
        if ($status -eq 403) { throw "$Method $Path -> 403: the API key's owner needs system.admin to create the bench entity." }
        throw "$Method $Path -> HTTP ${status}: $($_.ErrorDetails.Message)"
    }
}

# ── 1. Seed ──────────────────────────────────────────────────────────────────
Write-Host "=== 1. Seed $Entity ==="
$entities = Invoke-Bench -Method Get -Path "/api/v1/admin/entities"
$entityRow = @($entities) | Where-Object { $_.logicalname -eq $Entity } | Select-Object -First 1
if (-not $entityRow) {
    $entityRow = Invoke-Bench -Method Post -Path "/api/v1/admin/entities" -Body @{ logicalname = $Entity; name = "Bench load" }
    Invoke-Bench -Method Post -Path "/api/v1/admin/entities/$($entityRow.id)/fields" -AllowConflict `
        -Body @{ logicalname = "title"; name = "Title"; field_type = "text"; is_sortable = $true; is_filterable = $true } | Out-Null
    Invoke-Bench -Method Post -Path "/api/v1/admin/entities/$($entityRow.id)/fields" -AllowConflict `
        -Body @{ logicalname = "seq"; name = "Seq"; field_type = "number"; is_sortable = $true; is_filterable = $true } | Out-Null
    Write-Host "  created $Entity"
} else {
    Write-Host "  reusing $Entity"
}
$queries = Invoke-Bench -Method Get -Path "/api/v1/admin/queries"
$query = @($queries) | Where-Object { $_.name -eq $QueryName } | Select-Object -First 1
if (-not $query) {
    $tableDef = @(
        @{ logicalName = "seq"; displayName = "Seq"; dataType = "integer"; isSortable = $true; isSearchable = $false },
        @{ logicalName = "title"; displayName = "Title"; dataType = "text"; isSortable = $true; isSearchable = $true }
    )
    $query = Invoke-Bench -Method Post -Path "/api/v1/admin/queries" -Body @{
        name                = $QueryName
        sql_query           = "SELECT id, seq, title FROM $Entity WHERE is_active = true"
        table_definition    = ($tableDef | ConvertTo-Json -Depth 5 -Compress)
        entity_logical_name = $entityRow.id
        required_privilege  = "$Entity.read"
        is_report           = $false
    }
}

$jobs = @()
$seq = 0
while ($seq -lt $Rows) {
    $n = [Math]::Min(500, $Rows - $seq)
    $records = 1..$n | ForEach-Object { $seq++; @{ data = @{ title = "bulk-row-$seq"; seq = $seq } } }
    $resp = Invoke-Bench -Method Post -Path "/api/v1/$Entity/bulk" -Body @{ operation = "create"; records = $records }
    $jobs += $resp.id
}
foreach ($job in $jobs) {
    do {
        Start-Sleep -Milliseconds 500
        $status = Invoke-Bench -Method Get -Path "/api/v1/$Entity/bulk/$job"
    } while ($status.status -notin @("completed", "failed"))
    if ($status.status -eq "failed" -or $status.failed -gt 0) {
        Write-Warning "  bulk job ${job}: status=$($status.status) failed=$($status.failed)"
    }
}
Write-Host "  $Rows records seeded"

# ── 2. Run ───────────────────────────────────────────────────────────────────
Write-Host "=== 2. Run the production mix at concurrency $($levels -join ', ') ==="
$k6 = Get-Command k6 -ErrorAction SilentlyContinue
$summaries = @()
foreach ($level in $levels) {
    $file = "bench-$Profile-c$level.json"
    $out = Join-Path $ResultsDir $file
    if (Test-Path $out) { Remove-Item $out -Force }
    $env6 = @{
        BASE_URLS = $BaseUrl; API_KEY = $ApiKey; BULK_ENTITY = $Entity; BULK_QUERY_ID = $query.id
        BULK_ROW_COUNT = $Rows; DURATION = $Duration; RATE = $profileInfo.rated_rps; VUS = $level
    }
    $e = @()
    if ($k6) {
        foreach ($kv in $env6.GetEnumerator()) { $e += @("-e", "$($kv.Key)=$($kv.Value)") }
        & k6 run @e (Join-Path $LoadtestDir "k6/production_mix.js") `
            --summary-trend-stats "avg,min,med,p(50),p(90),p(95),p(99),max" --summary-export $out
    } else {
        # In a container, the host's own address is host.docker.internal.
        $env6.BASE_URLS = $BaseUrl -replace '//(localhost|127\.0\.0\.1)', '//host.docker.internal'
        foreach ($kv in $env6.GetEnumerator()) { $e += @("-e", "$($kv.Key)=$($kv.Value)") }
        & docker run --rm -v "$($LoadtestDir):/work" @e grafana/k6 run "/work/k6/production_mix.js" `
            --summary-trend-stats "avg,min,med,p(50),p(90),p(95),p(99),max" --summary-export "/work/results/$file"
    }
    if (-not (Test-Path $out)) { Write-Warning "concurrency $level produced no summary; see the k6 output above." }
    else { $summaries += "$level=$out" }
}

# ── 3. Compare ───────────────────────────────────────────────────────────────
Write-Host "=== 3. Compare ==="
$compareArgs = @()
foreach ($s in $summaries) { $compareArgs += @("--summary", $s) }
if ($Published) { $compareArgs += @("--published", $Published) }
if ($summaries.Count -gt 0) {
    & node (Join-Path $PSScriptRoot "bench-compare.mjs") @compareArgs
}

# ── 4. Clean up ──────────────────────────────────────────────────────────────
if ($KeepRecords) {
    Write-Host "=== 4. Clean up skipped (-KeepRecords) ==="
} else {
    Write-Host "=== 4. Delete the $Entity records ==="
    $deleted = 0
    while ($true) {
        $page = Invoke-Bench -Method Post -Path "/api/v1/query/execute" -Body @{ query_id = $query.id; page = 1; page_size = 200 }
        $ids = @($page.data.records | ForEach-Object { $_.id })
        if ($ids.Count -eq 0) { break }
        $resp = Invoke-Bench -Method Post -Path "/api/v1/$Entity/bulk" `
            -Body @{ operation = "delete"; records = @($ids | ForEach-Object { @{ id = $_; data = @{} } }) }
        do {
            Start-Sleep -Milliseconds 500
            $status = Invoke-Bench -Method Get -Path "/api/v1/$Entity/bulk/$($resp.id)"
        } while ($status.status -notin @("completed", "failed"))
        if ($status.status -eq "failed" -or $status.succeeded -eq 0) {
            throw "Deleting $Entity records stopped: bulk job $($resp.id) status=$($status.status)."
        }
        $deleted += $ids.Count
    }
    Write-Host "  deleted $deleted records"
}
