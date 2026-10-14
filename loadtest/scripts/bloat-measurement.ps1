# P-db-maintenance step 1 — seeded-load bloat/autovacuum measurement.
#
# Answers the plan's open question: are MUTABLE_STORAGE_PARAMS /
# APPEND_ONLY_STORAGE_PARAMS (crates/engine/attome-metadata/src/provision.rs) real
# numbers or still a guess? Runs sustained UPDATE churn against a mutable-class
# table pair (stock reloptions vs. the tuned ones actually shipped) and
# sustained INSERT churn against an append-only-class pair, snapshotting
# pg_stat_user_tables + table size on an interval throughout, so the
# dead-tuple/autovacuum-timing/size-growth behavior can be compared head to
# head instead of asserted.
#
# Deliberately pure-Postgres (psql + pgbench), no app nodes: this measures
# storage-layer behavior under provision_table's actual reloptions, not HTTP
# latency (that's loadtest/'s k6 matrix, a separate concern). Reuses the same
# isolated Postgres @5556 (`attome_loadtest`) and the same LOADTEST_ACK safety
# guard as the rest of this harness — never point this at attomedb/attome_dev.
#
# Environment caveat (same discipline as document_v2/docs/LOADTEST-2026-07-19.md):
# this runs on a single Windows dev machine, not the dedicated production-
# shaped host the plan calls for. Treat the *relative* shape (does the tuned
# table accumulate less dead-tuple ratio / trigger autovacuum sooner / hold
# size better than stock) as the trustworthy finding — not the absolute
# tuple counts or timings, which depend heavily on this machine's disk/CPU.
#
# Usage:
#   $env:LOADTEST_ACK = "yes"
#   docker compose -f docker-compose.loadtest.yml up -d postgres-loadtest
#   ./scripts/bloat-measurement.ps1
#   # Real seeded-volume pass (slow on a dev laptop, fine on a real host):
#   # ./scripts/bloat-measurement.ps1 -RowCount 10000000 -DurationSecs 600

param(
    [int]$RowCount = 300000,
    [int]$DurationSecs = 120,
    [int]$Clients = 8,
    [int]$SnapshotIntervalSecs = 5
)

. "$PSScriptRoot/common.ps1"
Assert-LoadtestSafety

$ConnStr = "postgresql://postgres:loadtest-throwaway-pw@$($script:LoadtestDbHost):$($script:LoadtestDbPort)/$($script:LoadtestDbName)"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$csvPath = Join-Path $script:ResultsDir "bloat-$stamp.csv"
$summaryPath = Join-Path $script:ResultsDir "bloat-summary-$stamp.json"
$genPgbenchDir = Join-Path $script:GenDir "pgbench"
New-Item -ItemType Directory -Force -Path $genPgbenchDir | Out-Null

"snapshot_epoch,table_name,n_live_tup,n_dead_tup,n_tup_ins,n_tup_upd,last_autovacuum,total_bytes" |
    Set-Content -Path $csvPath -Encoding utf8

Write-Host "Waiting for postgres-loadtest to accept connections..."
$deadline = (Get-Date).AddSeconds(60)
while ($true) {
    & psql $ConnStr -tAc "SELECT 1" *>$null
    if ($LASTEXITCODE -eq 0) { break }
    if ((Get-Date) -gt $deadline) { throw "postgres-loadtest not reachable at $($script:LoadtestDbHost):$($script:LoadtestDbPort) after 60s — is 'docker compose -f docker-compose.loadtest.yml up -d postgres-loadtest' running?" }
    Start-Sleep -Seconds 2
}

Write-Host "Building bloat_test schema + seeding mutable tables with $RowCount rows each..."
& psql $ConnStr -v "rowcount=$RowCount" -f (Join-Path $script:LoadtestDir "sql/bloat_setup.sql")
if ($LASTEXITCODE -ne 0) { throw "bloat_setup.sql failed" }

function New-PgbenchScript {
    param([string]$TemplateName, [string]$Table)
    $template = Get-Content (Join-Path $script:LoadtestDir "sql/pgbench/$TemplateName") -Raw
    $out = Join-Path $genPgbenchDir "$Table.sql"
    # Set-Content -Encoding utf8 writes a BOM on Windows PowerShell 5.1 (same
    # gotcha common.ps1 documents for generated JSON configs) -- pgbench's
    # simple-query parser chokes on a leading BOM byte ("syntax error at or
    # near ''"), so write UTF-8 without BOM explicitly instead.
    $rendered = $template -replace "__TABLE__", $Table
    [System.IO.File]::WriteAllText($out, $rendered, (New-Object System.Text.UTF8Encoding($false)))
    return $out
}

function Start-SnapshotJob {
    param([string]$ConnStr, [string[]]$Tables, [string]$CsvPath, [int]$IntervalSecs)
    $tableList = ($Tables | ForEach-Object { "'$_'" }) -join ","
    return Start-Job -ScriptBlock {
        param($ConnStr, $TableList, $CsvPath, $IntervalSecs)
        while ($true) {
            $epoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            $sql = @"
SELECT $epoch, relname, n_live_tup, n_dead_tup, n_tup_ins, n_tup_upd,
       coalesce(last_autovacuum::text, ''),
       pg_total_relation_size('bloat_test.' || relname)
FROM pg_stat_user_tables
WHERE schemaname = 'bloat_test' AND relname IN ($TableList)
"@
            $rows = & psql $ConnStr -tA -F "," -c $sql
            foreach ($r in $rows) { if ($r.Trim()) { Add-Content -Path $CsvPath -Value $r } }
            Start-Sleep -Seconds $IntervalSecs
        }
    } -ArgumentList $ConnStr, $tableList, $CsvPath, $IntervalSecs
}

function Invoke-BloatRun {
    param([string]$Label, [string]$Table, [string]$TemplateName, [int]$MaxSeq)
    Write-Host ""
    Write-Host "=== $Label : $Table ($DurationSecs s, $Clients clients) ==="
    $scriptFile = New-PgbenchScript -TemplateName $TemplateName -Table $Table
    $job = Start-SnapshotJob -ConnStr $ConnStr -Tables @($Table) -CsvPath $csvPath -IntervalSecs $SnapshotIntervalSecs
    try {
        & pgbench $ConnStr -f $scriptFile -D "maxseq=$MaxSeq" -c $Clients -j ([Math]::Min($Clients, 4)) -T $DurationSecs -n -P 15
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue | Out-Null
        Remove-Job $job -Force -ErrorAction SilentlyContinue | Out-Null
    }
    # One final snapshot immediately after the run stops, so the CSV always
    # has an end-of-run row even if the interval didn't land exactly on it.
    $epoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    & psql $ConnStr -tA -F "," -c "SELECT $epoch, relname, n_live_tup, n_dead_tup, n_tup_ins, n_tup_upd, coalesce(last_autovacuum::text,''), pg_total_relation_size('bloat_test.'||relname) FROM pg_stat_user_tables WHERE schemaname='bloat_test' AND relname='$Table'" |
        ForEach-Object { if ($_.Trim()) { Add-Content -Path $csvPath -Value $_ } }
}

# Mutable pair: UPDATE churn (row_version bump), sequential so autovacuum
# worker contention/disk I/O from one run never confounds the other's
# numbers. maxseq = RowCount for both (rows pre-seeded, addressed by seq_id).
Invoke-BloatRun -Label "mutable/stock" -Table "mutable_stock" -TemplateName "update_churn.template.sql" -MaxSeq $RowCount
Invoke-BloatRun -Label "mutable/tuned" -Table "mutable_tuned" -TemplateName "update_churn.template.sql" -MaxSeq $RowCount

# Append-only pair: INSERT-only churn (audit-family shape). maxseq is unused
# by the insert template (nextval-driven) but pgbench requires -D to define
# every :variable referenced across the run; passed harmlessly.
Invoke-BloatRun -Label "append/stock" -Table "append_stock" -TemplateName "insert_churn.template.sql" -MaxSeq $RowCount
Invoke-BloatRun -Label "append/tuned" -Table "append_tuned" -TemplateName "insert_churn.template.sql" -MaxSeq $RowCount

Write-Host ""
Write-Host "Waiting 20s for any in-flight autovacuum to settle before final snapshot..."
Start-Sleep -Seconds 20

$finalRows = & psql $ConnStr -tA -F "," -c @"
SELECT relname, n_live_tup, n_dead_tup, n_tup_ins, n_tup_upd,
       round(100.0 * n_dead_tup / greatest(n_live_tup + n_dead_tup, 1), 2) AS dead_pct,
       coalesce(last_autovacuum::text, 'never'),
       pg_size_pretty(pg_total_relation_size('bloat_test.' || relname))
FROM pg_stat_user_tables
WHERE schemaname = 'bloat_test'
ORDER BY relname
"@

$summary = [ordered]@{
    environment  = "single Windows dev machine, Docker Desktop, isolated postgres-loadtest @5556 — NOT the production-shaped host P-db-maintenance calls for; treat relative comparisons (stock vs tuned) as trustworthy, absolute numbers as this-machine-only"
    row_count    = $RowCount
    duration_secs = $DurationSecs
    clients      = $Clients
    generated_at = (Get-Date -Format "o")
    final_rows   = @($finalRows | ForEach-Object {
        $f = $_ -split ","
        [ordered]@{
            table = $f[0]; n_live_tup = $f[1]; n_dead_tup = $f[2]
            n_tup_ins = $f[3]; n_tup_upd = $f[4]; dead_pct = $f[5]
            last_autovacuum = $f[6]; total_size = $f[7]
        }
    })
}
$summary | ConvertTo-Json -Depth 4 | Set-Content -Path $summaryPath -Encoding utf8

Write-Host ""
Write-Host "=== Final pg_stat_user_tables snapshot ==="
$finalRows | ForEach-Object { Write-Host $_ }
Write-Host ""
Write-Host "Time series: $csvPath"
Write-Host "Summary:     $summaryPath"
