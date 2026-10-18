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
#
# AA1-T2: -Profile (default solo) reads records_per_entity, users and roles
# from loadtest/profiles.json. records_per_entity sizes loadtest_bulk unless
# -RowCount is passed explicitly. The profile's users are registered through
# the API, its roles created through the admin API and handed out
# round-robin, and each 500-record bulk chunk is posted by the next user in
# turn, so record ownership (the creator's share, D-133) is spread across
# them and record-level security has real work to do. A summary goes to
# loadtest/results/seed-<profile>.json; a re-run whose summary still matches
# the API's row count skips seeding, and one that finds fewer rows seeds only
# the difference. -DryRun prints the plan and exits without any HTTP call.
param(
    [string]$Profile = "solo",
    [switch]$DryRun,
    [int]$RowCount = 5000,       # overridden by the profile's records_per_entity
                                   # unless passed explicitly.
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
    [string]$TestPassword = "Loadtest-User-Pw1",
    [string]$ProfileUserPassword = "Loadtest-Profile-Pw1"
)
. "$PSScriptRoot/common.ps1"

# AA1-T2: the profile.
$profiles = Get-Content -Raw -Path (Join-Path $script:LoadtestDir "profiles.json") | ConvertFrom-Json
$profileSpec = $profiles.$Profile
if (-not $profileSpec -or $Profile -like "_*") {
    $names = ($profiles.PSObject.Properties.Name | Where-Object { $_ -notlike "_*" }) -join ", "
    throw "Unknown profile '$Profile'; profiles.json has: $names"
}
if (-not $PSBoundParameters.ContainsKey("RowCount")) {
    $RowCount = [int]$profileSpec.records_per_entity
}
$profileUsers = [int]$profileSpec.users
$profileRoles = [int]$profileSpec.roles
$plannedCounts = [ordered]@{
    loadtest_wide = 0
    loadtest_bulk = $RowCount
    loadtest_mut  = $MutRecordCount
    loadtest_ddl  = $DdlRowCount
}

if ($DryRun) {
    Write-Host "Profile '$Profile' ($($profileSpec.machine)), dry run: no HTTP call is made."
    foreach ($entity in $plannedCounts.Keys) {
        Write-Host ("  {0,-14} {1,12:N0} records" -f $entity, $plannedCounts[$entity])
    }
    Write-Host ("  users          {0,12:N0} (plus the admin and the test user)" -f $profileUsers)
    Write-Host ("  roles          {0,12:N0}" -f $profileRoles)
    Write-Host ("  bulk chunks    {0,12:N0} of up to 500 records" -f [Math]::Ceiling($RowCount / 500))
    exit 0
}

Assert-LoadtestSafety
$seedStarted = Get-Date
$summaryPath = Join-Path $script:ResultsDir "seed-$Profile.json"

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
# AA1-T2: the profile's users, through the same registration API.
$profileEmails = @(1..$profileUsers | ForEach-Object { "loadtest-p{0:D5}@attome.local" -f $_ })
foreach ($email in $profileEmails) {
    Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/auth/register" -Body @{ email = $email; password = $ProfileUserPassword } -AllowConflict | Out-Null
}
Write-Host "  registered $($profileEmails.Count) profile user(s)."
Stop-LoadtestNodes

Write-Host "=== Phase 2: reboot with bootstrap_admin_email set so the admin grant lands ==="
Start-LoadtestNodes -Count 1 -BootstrapAdminEmail $AdminEmail | Out-Null
$port = @(Get-LoadtestNodePorts)[0]
$baseUrl = "http://127.0.0.1:$port"

$adminCookieJar = Join-Path $script:GenDir "admin-cookies.txt"
Remove-Item $adminCookieJar -ErrorAction SilentlyContinue
Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/auth/login" -CookieJar $adminCookieJar `
    -Body @{ email = $AdminEmail; password = $AdminPassword } | Out-Null

# AA1-T2: the rows already there, by the previous run's stored query.
function Get-BulkRowCount {
    param($QueryId)
    if (-not $QueryId) { return $null }
    try {
        $page = Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/query/execute" -CookieJar $adminCookieJar `
            -Body @{ query_id = $QueryId; page = 1; page_size = 1; include_total = $true }
        return [long]$page.data.total
    } catch {
        return $null
    }
}
$previous = $null
if (Test-Path $summaryPath) {
    $previous = Get-Content -Raw -Path $summaryPath | ConvertFrom-Json
}
$existingBulk = if ($previous) { Get-BulkRowCount -QueryId $previous.bulk_query_id } else { $null }
if ($previous -and $null -ne $existingBulk -and
    $existingBulk -eq [long]$previous.counts.loadtest_bulk -and
    $existingBulk -eq $RowCount -and
    [int]$previous.users -eq $profileUsers -and [int]$previous.roles -eq $profileRoles) {
    Write-Host "Seed for profile '$Profile' already matches the API ($existingBulk loadtest_bulk rows); skipping."
    Stop-LoadtestNodes
    exit 0
}
if ($null -eq $existingBulk) { $existingBulk = 0 }

Write-Host "=== Roles for profile '$Profile' ($profileRoles), handed out round-robin ==="
$roleIds = @()
for ($r = 1; $r -le $profileRoles; $r++) {
    $roleName = "loadtest-role-{0:D3}" -f $r
    $role = Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/admin/security/roles" -CookieJar $adminCookieJar -AllowConflict `
        -Body @{ name = $roleName; description = "AA1-T2 load-test role" }
    if (-not $role) {
        $page = 1
        do {
            $list = Invoke-Api -Method Get -BaseUrl $baseUrl -Path "/api/v1/admin/security/roles?page=$page&page_size=200" -CookieJar $adminCookieJar
            $role = $list.items | Where-Object { $_.name -eq $roleName } | Select-Object -First 1
            $page++
        } while (-not $role -and $list.items.Count -eq 200)
    }
    $roleIds += $role.id
}
$userIds = @{}
for ($u = 0; $u -lt $profileEmails.Count; $u++) {
    $email = $profileEmails[$u]
    $found = Invoke-Api -Method Get -BaseUrl $baseUrl -Path "/api/v1/admin/security/users/lookup?email=$([uri]::EscapeDataString($email))" -CookieJar $adminCookieJar
    $user = @($found) | Where-Object { $_.email -eq $email } | Select-Object -First 1
    if (-not $user) { throw "profile user $email was registered but the lookup cannot find it" }
    $userIds[$email] = $user.id
    if ($roleIds.Count -gt 0) {
        Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/admin/security/users/$($user.id)/roles" -CookieJar $adminCookieJar -AllowConflict `
            -Body @{ role_id = $roleIds[$u % $roleIds.Count]; reason = "AA1-T2 load-test seed" } | Out-Null
    }
}

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

# AA1-T2: each profile user may create and bulk-load loadtest_bulk, so the
# chunks below can be posted as them.
foreach ($email in $profileEmails) {
    foreach ($action in @("read", "create", "bulk")) {
        Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/admin/security/grants" -CookieJar $adminCookieJar -AllowConflict `
            -Body @{ user_email = $email; privilege_key = "loadtest_bulk.$action" } | Out-Null
    }
}
# One cookie jar per profile user, logged in on first use.
$userJars = @{}
function Get-UserJar {
    param($Email)
    if (-not $userJars.ContainsKey($Email)) {
        $jar = Join-Path $script:GenDir ("user-cookies-{0}.txt" -f ($Email -replace '[^A-Za-z0-9]', '_'))
        Remove-Item $jar -ErrorAction SilentlyContinue
        Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/auth/login" -CookieJar $jar `
            -Body @{ email = $Email; password = $ProfileUserPassword } | Out-Null
        $userJars[$Email] = $jar
    }
    return $userJars[$Email]
}

# MAX_BULK_RECORDS is 500 (D-098) -- this used to be 5000 when this script
# was first written, before that cap was lowered; found by actually
# re-running the harness (a bulk POST above 500 now 422s).
$chunkSize = 500
# AA1-T2: a re-run seeds only the rows still missing.
$remaining = [Math]::Max(0, $RowCount - $existingBulk)
$seq = [int]$existingBulk
$jobIds = @()
$chunk = 0
while ($remaining -gt 0) {
    $n = [Math]::Min($chunkSize, $remaining)
    $records = 1..$n | ForEach-Object { $seq++; @{ data = @{ title = "bulk-row-$seq"; seq = $seq } } }
    # AA1-T2: round-robin across the profile's users; the admin when the
    # profile has none.
    $jar = if ($profileEmails.Count -gt 0) { Get-UserJar -Email $profileEmails[$chunk % $profileEmails.Count] } else { $adminCookieJar }
    $resp = Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/loadtest_bulk/bulk" -CookieJar $jar `
        -Body @{ operation = "create"; records = $records }
    $jobIds += [pscustomobject]@{ id = $resp.id; jar = $jar }
    $remaining -= $n
    $chunk++
    Write-Host "  enqueued chunk of $n (seq up to $seq), $remaining remaining"
}
Write-Host "  waiting for $($jobIds.Count) bulk job(s) to complete..."
foreach ($job in $jobIds) {
    $jobId = $job.id
    do {
        Start-Sleep -Milliseconds 500
        $status = Invoke-Api -Method Get -BaseUrl $baseUrl -Path "/api/v1/loadtest_bulk/bulk/$jobId" -CookieJar $job.jar
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

# AA1-T2: the API's own count of loadtest_bulk, for the summary.
$bulkTotal = Get-BulkRowCount -QueryId $bulkQuery.id

Stop-LoadtestNodes

$summary = [ordered]@{
    profile         = $Profile
    machine         = $profileSpec.machine
    counts          = [ordered]@{
        loadtest_wide = 0
        loadtest_bulk = if ($null -ne $bulkTotal) { $bulkTotal } else { $RowCount }
        loadtest_mut  = $mutIds.Count
        loadtest_ddl  = $ddlIds.Count
    }
    users           = $profileUsers
    roles           = $profileRoles
    bulk_query_id   = $bulkQuery.id
    elapsed_seconds = [Math]::Round(((Get-Date) - $seedStarted).TotalSeconds, 1)
    finished_at     = (Get-Date).ToUniversalTime().ToString("o")
}
$summary | ConvertTo-Json -Depth 5 | Set-Content -Path $summaryPath -Encoding utf8
Write-Host "Seed summary: $summaryPath ($($summary.elapsed_seconds) s)"

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
