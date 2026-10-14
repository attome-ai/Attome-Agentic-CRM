# P1.8d step 3 (+ part of step 1) — idempotent-per-run seed script. Boots a
# single node twice (bootstrap admin needs a real core_systemuser row to
# exist before security.bootstrap_admin_email can grant it system.admin —
# see attome_security::seed — so the first boot must NOT set it), then
# provisions:
#   - loadtest_wide   : 41 text fields, no bulk data — metadata-heavy entity
#                       for the metadata_read (schema) scenario
#   - loadtest_bulk   : title(text)+seq(number), -RowCount rows — the
#                       list_query/crud_read target
#   - loadtest_mut    : title(text)+counter(number), -MutRecordCount rows —
#                       dedicated targets for the mutating_write scenario so
#                       it never contends with the read scenarios' rows
#   - a stored query (core_sql_query) over loadtest_bulk for query/execute
#   - a non-admin test user with read/create/update/delete grants on
#     loadtest_bulk/loadtest_mut (including the dedicated `.bulk` grant;
#     list_query's stored query is gated on
#     loadtest_bulk.read too) — the "authz cache exercised, not bypassed"
#     requirement from the plan.
#
# HTTP calls go through curl (curl.exe on Windows, bundled with Windows 10+;
# the plain `curl` binary on Linux — see common.ps1's $script:CurlExe), not
# Invoke-RestMethod/Invoke-WebRequest -- .NET's WebRequest stack was
# unreliable against a just-started local node in this environment
# (intermittent "unable to connect" on the very first non-GET request after
# a successful health check, not reproducible via curl). Session state
# is a curl cookie jar file, not a WebSession object.
#
# Writes loadtest/.generated/seed-info.json with everything run-matrix.ps1
# and the k6 scripts need (entity ids, record id samples, credentials).
#
# Re-running is safe: registration/entity-creation 409s are caught and
# treated as "already seeded", not fatal. To start over, `docker compose
# -f docker-compose.loadtest.yml down -v` first.
param(
    [int]$RowCount = 5000,       # plan's ask is 1,000,000 (§3) — see README for why
                                   # this default is smaller for a single dev machine;
                                   # pass -RowCount 1000000 on a real dedicated host.
    [int]$MutRecordCount = 300,
    # P1.8d step 10 — dedicated target for the schema_change_ddl.js exercise.
    # Default stays under SCHEMA_CHANGE_INLINE_ROW_LIMIT (10,000, admin.rs)
    # so a quick smoke run exercises the inline `exec_ddl_locked` path only;
    # pass -DdlRowCount above 10000 on a real host to also exercise the
    # `ApplySchemaChangePlan` async job path (P-online-schema-change).
    [int]$DdlRowCount = 500,
    [string]$AdminEmail = "loadtest-admin@attome.local",
    [string]$AdminPassword = "Loadtest-Admin-Pw1",
    [string]$TestEmail = "loadtest-user@attome.local",
    [string]$TestPassword = "Loadtest-User-Pw1"
)
. "$PSScriptRoot/common.ps1"
Assert-LoadtestSafety

function Invoke-Api {
    param($Method, $BaseUrl, $Path, $CookieJar = $null, $Body = $null, [switch]$AllowConflict)
    $uri = "$BaseUrl$Path"
    # Sec-Fetch-Site: every seeding call below is a cookie-authenticated POST,
    # which `attome_server::middleware::csrf::csrf_protect`
    # (P-cookie-csrf-hardening, added after this script was written) rejects
    # with 403 unless it carries the browser signal a real same-origin tab
    # sends — `security.csrf_enforce` defaults true and New-LoadtestConfig
    # never overrides it, so without this the seed fails at the first
    # /api/v1/auth/register. Same fix, same reason as k6/lib/http.js's
    # jsonHeaders. Found by TODO-014's pre-run pass.
    $curlArgs = @("-s", "-X", $Method.ToString().ToUpper(), $uri,
        "-H", "Content-Type: application/json",
        "-H", "Sec-Fetch-Site: same-origin",
        "-w", "`n%{http_code}")
    if ($CookieJar) { $curlArgs += @("-b", $CookieJar, "-c", $CookieJar) }
    $bodyFile = $null
    if ($null -ne $Body) {
        # A JSON string passed directly as a curl -d argument gets mangled by
        # Windows' command-line reconstruction for native exes (embedded `"`
        # characters) -- writing it to a temp file and using --data-binary
        # @file sidesteps quoting entirely.
        $bodyFile = Join-Path $script:GenDir "body-$([guid]::NewGuid()).json"
        $json = $Body | ConvertTo-Json -Depth 10 -Compress
        [System.IO.File]::WriteAllText($bodyFile, $json, (New-Object System.Text.UTF8Encoding($false)))
        $curlArgs += @("--data-binary", "@$bodyFile")
    }

    try {
        $attempts = 0
        while ($true) {
            $attempts++
            $raw = & $script:CurlExe --connect-timeout 5 @curlArgs 2>$null
            $exitCode = $LASTEXITCODE
            if ($exitCode -ne 0 -or -not $raw) {
                if ($attempts -lt 5) { Start-Sleep -Milliseconds 500; continue }
                throw "$($script:CurlExe) failed after $attempts attempts (exit $exitCode): $Method $Path -> $uri"
            }
            break
        }
    } finally {
        if ($bodyFile) { Remove-Item $bodyFile -ErrorAction SilentlyContinue }
    }

    $lines = @($raw)
    $statusCode = [int]$lines[-1]
    $bodyText = ($lines[0..($lines.Length - 2)] -join "`n")

    if ($statusCode -ge 200 -and $statusCode -lt 300) {
        if ($bodyText) { return $bodyText | ConvertFrom-Json } else { return $null }
    }
    if ($AllowConflict -and ($statusCode -eq 409 -or $statusCode -eq 422)) {
        Write-Host "  (already exists, skipping: $Path)"
        return $null
    }
    throw "API call failed: $Method $Path -> HTTP ${statusCode}: $bodyText"
}

Write-Host "=== Phase 1: boot without bootstrap_admin_email, register admin + test user ==="
Start-LoadtestNodes -Count 1 -BootstrapAdminEmail "" | Out-Null
$port = @(Get-LoadtestNodePorts)[0]
$baseUrl = "http://127.0.0.1:$port"

Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/auth/register" -Body @{ email = $AdminEmail; password = $AdminPassword } -AllowConflict | Out-Null
Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/auth/register" -Body @{ email = $TestEmail; password = $TestPassword } -AllowConflict | Out-Null
Stop-LoadtestNodes

Write-Host "=== Phase 2: reboot with bootstrap_admin_email set so the admin grant lands ==="
Start-LoadtestNodes -Count 1 -BootstrapAdminEmail $AdminEmail | Out-Null
$port = @(Get-LoadtestNodePorts)[0]
$baseUrl = "http://127.0.0.1:$port"

$adminCookieJar = Join-Path $script:GenDir "admin-cookies.txt"
Remove-Item $adminCookieJar -ErrorAction SilentlyContinue
Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/auth/login" -CookieJar $adminCookieJar `
    -Body @{ email = $AdminEmail; password = $AdminPassword } | Out-Null

Write-Host "=== Provisioning loadtest_wide (41 text fields) ==="
$wide = Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/admin/entities" -CookieJar $adminCookieJar -AllowConflict `
    -Body @{ logicalname = "loadtest_wide"; name = "Loadtest Wide" }
if (-not $wide) {
    $wide = (Invoke-Api -Method Get -BaseUrl $baseUrl -Path "/api/v1/admin/entities" -CookieJar $adminCookieJar) |
        Where-Object { $_.logicalname -eq "loadtest_wide" } | Select-Object -First 1
}
for ($i = 1; $i -le 40; $i++) {
    $fname = "field_{0:D2}" -f $i
    Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/admin/entities/$($wide.id)/fields" -CookieJar $adminCookieJar -AllowConflict `
        -Body @{ logicalname = $fname; name = $fname; field_type = "text" } | Out-Null
}

Write-Host "=== Provisioning loadtest_bulk (title, seq) + $RowCount rows ==="
$bulk = Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/admin/entities" -CookieJar $adminCookieJar -AllowConflict `
    -Body @{ logicalname = "loadtest_bulk"; name = "Loadtest Bulk" }
if (-not $bulk) {
    $bulk = (Invoke-Api -Method Get -BaseUrl $baseUrl -Path "/api/v1/admin/entities" -CookieJar $adminCookieJar) |
        Where-Object { $_.logicalname -eq "loadtest_bulk" } | Select-Object -First 1
}
Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/admin/entities/$($bulk.id)/fields" -CookieJar $adminCookieJar -AllowConflict `
    -Body @{ logicalname = "title"; name = "Title"; field_type = "text"; is_sortable = $true; is_filterable = $true } | Out-Null
Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/admin/entities/$($bulk.id)/fields" -CookieJar $adminCookieJar -AllowConflict `
    -Body @{ logicalname = "seq"; name = "Seq"; field_type = "number"; is_sortable = $true; is_filterable = $true } | Out-Null

# Same registry-catchup race as loadtest_mut below, but worse here: the
# apalis worker can pick up the bulk job before the metadata registry's
# pub/sub catch-up has registered the two fields just created, failing
# every record with "unknown field(s): seq, title" (found by actually
# running this against a live worker).
Start-Sleep -Milliseconds 750

# MAX_BULK_RECORDS is 500 (D-098) -- this used to be 5000 when this script
# was first written, before that cap was lowered; found by actually
# re-running the harness (a bulk POST above 500 now 422s).
$chunkSize = 500
$remaining = $RowCount
$seq = 0
$jobIds = @()
while ($remaining -gt 0) {
    $n = [Math]::Min($chunkSize, $remaining)
    $records = 1..$n | ForEach-Object { $seq++; @{ data = @{ title = "bulk-row-$seq"; seq = $seq } } }
    $resp = Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/loadtest_bulk/bulk" -CookieJar $adminCookieJar `
        -Body @{ operation = "create"; records = $records }
    $jobIds += $resp.id
    $remaining -= $n
    Write-Host "  enqueued chunk of $n (seq up to $seq), $remaining remaining"
}
Write-Host "  waiting for $($jobIds.Count) bulk job(s) to complete..."
foreach ($jobId in $jobIds) {
    do {
        Start-Sleep -Milliseconds 500
        $status = Invoke-Api -Method Get -BaseUrl $baseUrl -Path "/api/v1/loadtest_bulk/bulk/$jobId" -CookieJar $adminCookieJar
    } while ($status.status -notin @("completed", "failed"))
    if ($status.status -eq "failed" -or $status.failed -gt 0) {
        Write-Warning "  bulk job ${jobId}: status=$($status.status) succeeded=$($status.succeeded) failed=$($status.failed)"
    }
}
Write-Host "  loadtest_bulk seeding done."

Write-Host "=== Provisioning loadtest_mut (title, counter) + $MutRecordCount rows ==="
$mut = Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/admin/entities" -CookieJar $adminCookieJar -AllowConflict `
    -Body @{ logicalname = "loadtest_mut"; name = "Loadtest Mutation Target" }
if (-not $mut) {
    $mut = (Invoke-Api -Method Get -BaseUrl $baseUrl -Path "/api/v1/admin/entities" -CookieJar $adminCookieJar) |
        Where-Object { $_.logicalname -eq "loadtest_mut" } | Select-Object -First 1
}
Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/admin/entities/$($mut.id)/fields" -CookieJar $adminCookieJar -AllowConflict `
    -Body @{ logicalname = "title"; name = "Title"; field_type = "text" } | Out-Null
Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/admin/entities/$($mut.id)/fields" -CookieJar $adminCookieJar -AllowConflict `
    -Body @{ logicalname = "counter"; name = "Counter"; field_type = "number" } | Out-Null

# The arc-swap metadata registry catches up via a ~250ms-debounced Redis
# pub/sub doorbell (Plan 1.2/1.14) -- a record-create immediately following
# entity/field creation can race ahead of that debounce and 404. A short
# wait here is cheaper than teaching Invoke-Api to retry on 404 generically.
Start-Sleep -Milliseconds 750

$mutIds = @()
for ($i = 1; $i -le $MutRecordCount; $i++) {
    $rec = Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/loadtest_mut" -CookieJar $adminCookieJar `
        -Body @{ title = "mut-row-$i"; counter = 0 }
    $mutIds += $rec.id
}
Write-Host "  created $($mutIds.Count) loadtest_mut rows."

Write-Host "=== Provisioning loadtest_ddl (title, counter) + $DdlRowCount rows ==="
# P1.8d step 10 — dedicated target for schema_change_ddl.js: `title` is the
# field the DDL VUs toggle `is_required`/`max_length` on (never touched by
# the concurrent write VUs), `counter` is what the write VUs PATCH instead
# (mirrors loadtest_mut's title/counter split, same reasoning — the two
# traffic classes must never collide on the same column). A dedicated entity
# rather than reusing loadtest_mut so this exercise's schema churn can never
# affect mutating_write.js's own row-version expectations.
$ddl = Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/admin/entities" -CookieJar $adminCookieJar -AllowConflict `
    -Body @{ logicalname = "loadtest_ddl"; name = "Loadtest DDL Target" }
if (-not $ddl) {
    $ddl = (Invoke-Api -Method Get -BaseUrl $baseUrl -Path "/api/v1/admin/entities" -CookieJar $adminCookieJar) |
        Where-Object { $_.logicalname -eq "loadtest_ddl" } | Select-Object -First 1
}
$ddlTitleField = Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/admin/entities/$($ddl.id)/fields" -CookieJar $adminCookieJar -AllowConflict `
    -Body @{ logicalname = "title"; name = "Title"; field_type = "text" }
if (-not $ddlTitleField) {
    $ddlTitleField = (Invoke-Api -Method Get -BaseUrl $baseUrl -Path "/api/v1/admin/entities/$($ddl.id)/fields" -CookieJar $adminCookieJar) |
        Where-Object { $_.logicalname -eq "title" } | Select-Object -First 1
}
Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/admin/entities/$($ddl.id)/fields" -CookieJar $adminCookieJar -AllowConflict `
    -Body @{ logicalname = "counter"; name = "Counter"; field_type = "number" } | Out-Null

# Same registry-catchup race as loadtest_mut above.
Start-Sleep -Milliseconds 750

$ddlIds = @()
for ($i = 1; $i -le $DdlRowCount; $i++) {
    # `title` always non-null on insert -- SET NOT NULL never needs a
    # backfill in this exercise (that's schema_change.rs's own, separately
    # tested, concern), keeping this scenario focused purely on lock
    # contention.
    $rec = Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/loadtest_ddl" -CookieJar $adminCookieJar `
        -Body @{ title = "ddl-row-$i"; counter = 0 }
    $ddlIds += $rec.id
}
Write-Host "  created $($ddlIds.Count) loadtest_ddl rows. field_id for schema_change_ddl.js: $($ddlTitleField.id)"

Write-Host "=== Stored query for query/execute (list_query scenario) ==="
$tableDef = @(
    @{ logicalName = "seq"; displayName = "Seq"; dataType = "integer"; isSortable = $true; isSearchable = $false },
    @{ logicalName = "title"; displayName = "Title"; dataType = "text"; isSortable = $true; isSearchable = $true }
)
# NOTE: create_entity already auto-generates its own default query for
# every entity (ensure_default_query, no table_definition/required_privilege)
# — query/execute's entity-name lookup picks whichever query for that entity
# has the EARLIEST created_at, which is always that auto-generated one, never
# this one. So list_query.js must reference this query by its exact
# query_id, not by entity name — capture the id here (fetching by name on
# AllowConflict's re-run path, same fallback pattern as the entities above).
$bulkQuery = Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/admin/queries" -CookieJar $adminCookieJar -AllowConflict -Body @{
    name                 = "loadtest_bulk_list_custom"
    sql_query            = "SELECT id, seq, title FROM loadtest_bulk WHERE is_active = true"
    table_definition      = ($tableDef | ConvertTo-Json -Depth 5 -Compress)
    entity_logical_name  = $bulk.id
    required_privilege   = "loadtest_bulk.read"
    is_report            = $false
}
if (-not $bulkQuery) {
    $bulkQuery = (Invoke-Api -Method Get -BaseUrl $baseUrl -Path "/api/v1/admin/queries" -CookieJar $adminCookieJar) |
        Where-Object { $_.name -eq "loadtest_bulk_list_custom" } | Select-Object -First 1
}

Write-Host "=== Grants for the non-admin test user (exercises the authz cache, not bypassed) ==="
foreach ($entity in @("loadtest_bulk", "loadtest_mut", "loadtest_ddl")) {
    foreach ($action in @("read", "create", "update", "delete", "bulk")) {
        Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/admin/security/grants" -CookieJar $adminCookieJar -AllowConflict `
            -Body @{ user_email = $TestEmail; privilege_key = "$entity.$action" } | Out-Null
    }
}

Stop-LoadtestNodes

$seedInfo = @{
    admin_email    = $AdminEmail
    admin_password = $AdminPassword
    test_email     = $TestEmail
    test_password  = $TestPassword
    wide_entity    = "loadtest_wide"
    bulk_entity    = "loadtest_bulk"
    bulk_query_id  = $bulkQuery.id
    mut_entity     = "loadtest_mut"
    bulk_row_count = $RowCount
    mut_record_ids = $mutIds
    ddl_entity     = "loadtest_ddl"
    ddl_entity_id  = $ddl.id
    ddl_field_id   = $ddlTitleField.id
    ddl_row_count  = $DdlRowCount
    ddl_record_ids = $ddlIds
}
$seedInfo | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $script:GenDir "seed-info.json") -Encoding utf8

Write-Host ""
Write-Host "Seed complete. loadtest/.generated/seed-info.json written for run-matrix.ps1/k6 scripts."
